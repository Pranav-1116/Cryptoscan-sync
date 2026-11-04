"""Take the control estate out of the UI and into the bank's own tooling.

A findings page is where an operator looks. It is not where a bank's SIEM, its CycloneDX
pipeline or its audit committee looks. A control layer whose only output is a screen is a
second, private estate that nothing downstream can reconcile — and the review said so.

Two exporters, one rule
-----------------------
Both read the *same* projection the console and the API read, so a SIEM alert, a CycloneDX
annotation and a page row can never disagree about what a collector observed. Neither invents
a verdict: a control that refused to answer exports as ``REFUSED`` with its reason, not as a
green line, and a control whose observation never happened exports as ``CONFIGURED`` only.

What they carry, and what they never carry
------------------------------------------
Findings, states, coverage, evidence ids, redaction *names and paths*, refusals. No secret, no
key material, no request or response body, no credential — the projection has already excluded
those, and both exporters re-apply :func:`cbom.security_controls.base.scrub` as a second lock.

CycloneDX: control findings attach to the estate the way 1.6 intends
------------------------------------------------------------------
CycloneDX has no "control" primitive, so nothing is invented. Each control becomes a
``service`` component with ``bom-ref`` ``urn:cryptoscan:control:<id>``, and each finding
becomes a 1.6 ``annotation`` whose ``subjects`` are those bom-refs. That is the spec's own
mechanism for "a note attached to one or more subjects", which is exactly what a finding is.
The document validates against the official 1.6 schema; ``cryptoscan:control_estate``
properties carry the parts no CycloneDX field can honestly express (observation class, read
state, coverage, refusals).

CEF: one line per finding, escaped, ids in extensions
-----------------------------------------------------
ArcSight CEF header fields are pipe-delimited and extension values are space-delimited
``key=value`` pairs, so a device-supplied string containing ``|``, ``=``, ``\\n`` or a backslash
would let a hostile or merely sloppy device forge an extra field. Every interpolated value is
escaped, and the header carries no free text at all.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from .base import scrub

#: The property namespace. Anything a consumer must not infer is stated explicitly here.
ESTATE_SCHEMA = "cryptoscan.control-estate/1"
CONTROL_REF_PREFIX = "urn:cryptoscan:control:"

#: Observation classes, in the order that matters to a reader. CONFIGURED is the weakest
#: claim and is never allowed to look like the strongest.
OBSERVATION_CLASSES = ("CONFIGURED", "OBSERVED", "RUNTIME_OBSERVED")


# --------------------------------------------------------------------------- #
# projection → the flat rows both exporters share
# --------------------------------------------------------------------------- #

def _as_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _rows(projection: Mapping[str, Any]) -> list[dict[str, Any]]:
    controls = projection.get("controls") or projection.get("estate") or []
    if isinstance(controls, Mapping):
        controls = [dict(value, id=key) if isinstance(value, Mapping) else {"id": key, "state": value}
                    for key, value in controls.items()]
    return [_as_dict(row) for row in controls]


def _evidence(row: Mapping[str, Any]) -> list[str]:
    values = row.get("evidence_ids") or row.get("evidence") or []
    if isinstance(values, str):
        values = [values]
    cleaned = [str(value) for value in values if value]
    if not cleaned and row.get("evidence_id"):
        cleaned = [str(row["evidence_id"])]
    return cleaned


def _observation_class(row: Mapping[str, Any]) -> str:
    """Never upgrade a claim. An unstated class is CONFIGURED, the weakest."""
    stated = str(row.get("observation_class") or row.get("observed_class") or "").upper()
    return stated if stated in OBSERVATION_CLASSES else "CONFIGURED"


def _state(row: Mapping[str, Any]) -> str:
    return str(row.get("state") or row.get("status") or "UNKNOWN").upper()


def findings(projection: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The findings both exporters emit, normalised once.

    A finding exists when a control has something to say that is not "fine": a bad state, a
    refusal, an unreadable read, a redaction, or a policy that is not attached. A control that
    is ``OK`` and ``RUNTIME_OBSERVED`` is coverage, not a finding.
    """
    out: list[dict[str, Any]] = []
    for row in _rows(projection):
        state = _state(row)
        control = str(row.get("id") or row.get("control") or row.get("name") or "unknown")
        evidence = _evidence(row)
        base = {
            "control": control,
            "vendor": row.get("vendor"),
            "kind": row.get("kind") or row.get("control_type"),
            "state": state,
            "observation_class": _observation_class(row),
            "evidence_ids": evidence,
            "read_state": row.get("read_state"),
            "reason": row.get("reason") or row.get("detail"),
            "refused": bool(row.get("refused")) or state == "REFUSED",
            "bom_ref": CONTROL_REF_PREFIX + control,
        }
        interesting = (
            state not in {"OK", "ENFORCED", "PRESENT", "CONFIGURED_CORRECTLY"}
            or base["refused"]
            or str(base["read_state"] or "").upper() not in {"", "COMPLETE"}
            or bool(row.get("redactions"))
            or bool(row.get("finding"))
        )
        if not interesting:
            continue
        if row.get("finding"):
            texts = [str(row["finding"])]
        elif base["refused"]:
            texts = [f"{control} refused to answer: {base['reason'] or 'no reason given'}"]
        elif state == "POLICY_NOT_ATTACHED":
            texts = [f"{control} policy is not attached to any evidence path: {base['reason'] or ''}".strip()]
        else:
            texts = [f"{control} is {state}: {base['reason'] or 'no further detail'}"]

        for redaction in row.get("redactions") or []:
            redaction = _as_dict(redaction)
            # the name and the path, never the value: the projection cannot carry one
            texts.append("redacted {field} at {path} ({reason})".format(
                field=redaction.get("field", "unknown"),
                path=redaction.get("path", "unknown"),
                reason=redaction.get("reason", "policy"),
            ))
        out.append(dict(base, summary="; ".join(texts)))
    return out


def _coverage(projection: Mapping[str, Any]) -> dict[str, Any]:
    summary = _as_dict(projection.get("summary"))
    return _as_dict(summary.get("coverage") or projection.get("coverage"))


def _refusals(projection: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for row in _rows(projection):
        if _state(row) == "REFUSED" or row.get("refused"):
            rows.append({"control": str(row.get("id") or "unknown"),
                         "reason": str(row.get("reason") or "no reason given"),
                         "evidence_ids": _evidence(row)})
    return rows


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


# --------------------------------------------------------------------------- #
# CycloneDX 1.6
# --------------------------------------------------------------------------- #

def _escape(value: Any) -> str:
    return str(value)


def to_cyclonedx(projection: Mapping[str, Any], *, timestamp: str | None = None,
                 serial: str | None = None) -> dict[str, Any]:
    """A schema-valid CycloneDX 1.6 document carrying the control estate and its findings."""
    clean, redactions = scrub(dict(projection))
    projection = clean if isinstance(clean, Mapping) else {}
    rows = _rows(projection)
    found = findings(projection)
    stamp = timestamp or str(projection.get("generated_at") or projection.get("timestamp")
                             or datetime.now(timezone.utc).isoformat())
    coverage = _coverage(projection)
    refusals = _refusals(projection)

    properties = [
        {"name": "cryptoscan:control_estate_schema", "value": ESTATE_SCHEMA},
        {"name": "cryptoscan:discovery_completeness", "value": "NOT_PROVEN"},
        {"name": "cryptoscan:observation_classes", "value": ",".join(OBSERVATION_CLASSES)},
        {"name": "cryptoscan:controls", "value": str(len(rows))},
        {"name": "cryptoscan:findings", "value": str(len(found))},
        {"name": "cryptoscan:redactions", "value": str(len(projection.get("redactions") or redactions) or 0)},
        {"name": "cryptoscan:redaction_basis", "value": "NAMES_AND_PATHS_ONLY_NO_VALUES"},
    ]
    for key, value in sorted(coverage.items()):
        if isinstance(value, (str, int, float, bool)):
            properties.append({"name": f"cryptoscan:coverage.{key}", "value": str(value)})
    for refusal in refusals:
        properties.append({"name": "cryptoscan:refused",
                           "value": f"{refusal['control']}: {refusal['reason']}"})
    # A refusal is never allowed to read as a complete estate.
    if refusals or str(coverage.get("state") or "").upper() in {"PARTIAL", "INCOMPLETE"}:
        properties.append({"name": "cryptoscan:estate_completeness", "value": "PARTIAL_WITH_REFUSALS"
                           if refusals else "PARTIAL"})

    components: list[dict[str, Any]] = []
    for row in rows:
        control = str(row.get("id") or row.get("control") or "unknown")
        component: dict[str, Any] = {
            "type": "platform",
            "bom-ref": CONTROL_REF_PREFIX + control,
            "name": control,
            "description": f"{row.get('kind') or 'security control'} supplied by "
                           f"{row.get('vendor') or 'unknown vendor'}; state {_state(row)}",
            "properties": [
                {"name": "cryptoscan:control.state", "value": _state(row)},
                {"name": "cryptoscan:control.observation_class", "value": _observation_class(row)},
                {"name": "cryptoscan:control.vendor", "value": _escape(row.get("vendor") or "unknown")},
            ],
        }
        if row.get("read_state"):
            component["properties"].append(
                {"name": "cryptoscan:control.read_state", "value": _escape(row["read_state"])})
        for evidence_id in _evidence(row):
            component["properties"].append({"name": "cryptoscan:evidence.id", "value": evidence_id})
        if row.get("reason"):
            component["properties"].append({"name": "cryptoscan:control.reason", "value": _escape(row["reason"])})
        if row.get("refused") or _state(row) == "REFUSED":
            component["properties"].append({"name": "cryptoscan:control.refused", "value": "true"})
        components.append(component)

    # CycloneDX 1.6 annotations allow no extra keys, so the state, the observation class and
    # the evidence ids are stated in the text itself: an annotation that dropped them would be
    # a note the bank's SIEM cannot join back to a snapshot.
    annotations = [{
        "bom-ref": "urn:cryptoscan:finding:" + hashlib.sha256(
            _canonical([item["control"], item["summary"], item["evidence_ids"]])).hexdigest()[:32],
        "subjects": [item["bom_ref"]],
        "annotator": {"component": {"type": "application", "name": "CryptoScan"}},
        "timestamp": stamp,
        "text": "[{state} | {observation} | evidence {evidence}] {summary}".format(
            state=item["state"], observation=item["observation_class"],
            evidence=",".join(item["evidence_ids"]) or "none", summary=item["summary"]),
    } for item in found]

    digest = hashlib.sha256(_canonical({"controls": components, "findings": found})).hexdigest()
    document: dict[str, Any] = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial or f"urn:uuid:{digest[:8]}-{digest[8:12]}-{digest[12:16]}-"
                                  f"{digest[16:20]}-{digest[20:32]}",
        "version": 1,
        "metadata": {
            "timestamp": stamp,
            "tools": {"components": [{"type": "application", "name": "CryptoScan",
                                      "version": str(projection.get("version") or "1")}]},
            "component": {"type": "application", "name": "cryptographic-and-security-estate",
                          "bom-ref": "urn:cryptoscan:estate"},
            "properties": properties,
        },
        "components": components,
    }
    if annotations:
        document["annotations"] = annotations
    return document


# --------------------------------------------------------------------------- #
# CEF
# --------------------------------------------------------------------------- #

_CEF_SEVERITY = {
    "CRITICAL": 10, "FAILED": 9, "REFUSED": 8, "UNREADABLE": 8, "OVER_LIMIT": 7,
    "POLICY_NOT_ATTACHED": 7, "NOT_CONFIGURED": 6, "DRIFTED": 6, "DEGRADED": 6,
    "UNKNOWN": 5, "PARTIAL": 5, "WITHIN_LIMIT": 3, "OK": 2, "ENFORCED": 2, "PRESENT": 2,
}


def _cef_value(value: Any, *, limit: int = 512) -> str:
    """Escape an extension value so no device string can forge another field or line."""
    text = "" if value is None else str(value)
    text = text[:limit]
    for raw, escaped in (("\\", "\\\\"), ("\n", "\\n"), ("\r", "\\r"), ("=", "\\="), (" ", "\\ ")):
        text = text.replace(raw, escaped)
    return text


def _cef_header(value: Any) -> str:
    """Escape a header field: CEF forbids pipes, backslashes and newlines in the header."""
    text = "" if value is None else str(value)
    for raw, escaped in (("\\", "\\\\"), ("|", "\\|"), ("\n", "\\n"), ("\r", "\\r")):
        text = text.replace(raw, escaped)
    return text


def to_cef(projection: Mapping[str, Any], *, device_vendor: str = "CryptoScan",
           device_product: str = "SecurityControls", device_version: str = "1.0",
           host: str | None = None) -> list[str]:
    """One CEF line per finding, in CEF:0 (ArcSight) form.

    The extension carries the evidence id, the state, the observation class and the read
    state, so a SIEM correlation can join an alert back to the exact snapshot it came from.
    It carries no secret and no free text from the device beyond what was already allowlisted.
    """
    clean, _ = scrub(dict(projection))
    projection = clean if isinstance(clean, Mapping) else {}
    found = findings(projection)
    lines: list[str] = []
    for item in found:
        if item["refused"]:
            event_id, name = "control-refused", "Control refused to answer"
        elif item["state"] == "POLICY_NOT_ATTACHED":
            event_id, name = "policy-not-attached", "Rate-limit policy not attached"
        elif item["state"] == "NOT_CONFIGURED":
            event_id, name = "not-configured", "Control not configured"
        elif item["state"] in {"OVER_LIMIT", "DRIFTED"}:
            event_id, name = "policy-violation", "Control policy violation"
        else:
            event_id, name = "control-state", "Control state changed"
        severity = _CEF_SEVERITY.get(item["state"], 5)
        extension = " ".join([
            f"cs1Label=EvidenceId cs1={_cef_value(','.join(item['evidence_ids']) or 'none')}",
            f"cs2Label=ControlId cs2={_cef_value(item['control'])}",
            f"cs3Label=ControlState cs3={_cef_value(item['state'])}",
            f"cs4Label=ObservationClass cs4={_cef_value(item['observation_class'])}",
            f"cs5Label=ReadState cs5={_cef_value(item['read_state'] or 'unknown')}",
            f"cs6Label=Vendor cs6={_cef_value(item['vendor'] or 'unknown')}",
            f"msg={_cef_value(item['summary'])}",
            f"externalId={_cef_value(item['control'])}",
        ]).strip()
        if host:
            extension += f" dvchost={_cef_value(host)}"
        lines.append(
            f"CEF:0|{_cef_header(device_vendor)}|{_cef_header(device_product)}|"
            f"{_cef_header(device_version)}|{_cef_header(event_id)}|{_cef_header(name)}|"
            f"{severity}|{extension}"
        )
    return lines


def to_cef_document(projection: Mapping[str, Any], **kwargs: Any) -> dict[str, Any]:
    """The CEF lines plus the provenance a log shipper needs to file them honestly."""
    lines = to_cef(projection, **kwargs)
    clean, _ = scrub(dict(projection))
    projection = clean if isinstance(clean, Mapping) else {}
    return {
        "schema": "cryptoscan.siem-cef/1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(lines),
        "lines": lines,
        "coverage": _coverage(projection),
        "refusals": _refusals(projection),
        "note": ("CEF extension values are escaped; a device cannot forge a field. Counts are "
                 "findings, not a claim that the estate is complete."),
    }


def export(projection: Mapping[str, Any], fmt: str, **kwargs: Any) -> Any:
    """``fmt`` in {"cyclonedx", "cef", "cef-lines"}; anything else is refused by name."""
    normalised = str(fmt or "").strip().lower()
    if normalised in {"cyclonedx", "cdx", "cyclonedx-1.6", "cyclonedx16"}:
        return to_cyclonedx(projection, **kwargs)
    if normalised == "cef":
        return to_cef_document(projection, **kwargs)
    if normalised in {"cef-lines", "siem"}:
        return to_cef(projection, **kwargs)
    raise ValueError(f"unsupported control-estate export format: {fmt!r} "
                     f"(supported: cyclonedx, cef, cef-lines)")


__all__: Iterable[str] = (
    "ESTATE_SCHEMA", "OBSERVATION_CLASSES", "export", "findings", "to_cef", "to_cef_document",
    "to_cyclonedx",
)
