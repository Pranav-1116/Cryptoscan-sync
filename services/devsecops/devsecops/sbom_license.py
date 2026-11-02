"""License compliance for SBOM documents.

Deterministic, offline, and deliberately modest about what it claims:

* ``license_inventory(bom)`` — every declared license grouped by SPDX
  identifier with the components carrying it, plus the components that declare
  nothing at all (an undeclared license is reported as *undeclared*, never as
  permitted or denied).
* ``check_license_policy(bom, policy)`` — violations against a policy of
  forbidden/restricted identifiers, an optional "must declare" rule, and a
  copyleft review trigger.

The review trigger is a **policy flag, not a legal determination**: strong
copyleft code combined with components whose license is undeclared or declared
proprietary is exactly the combination a lawyer needs to look at, so it is
surfaced for review with that wording. The engine does not model license
compatibility matrices — claiming that GPL-x is or isn't compatible with
license-y would be legal advice this platform has no basis to give.

License expressions are normalized the way SPDX defines them: parentheses are
dropped, ``AND``/``OR`` split the ids, ``WITH`` keeps the base license and
records the exception.
"""
from __future__ import annotations

import re
from typing import Any

# Classification used for the review trigger only. SPDX ids, compared
# case-insensitively; ``-or-later``/``+`` variants resolve to their base entry.
STRONG_COPYLEFT = (
    "AGPL-1.0-only", "AGPL-3.0-only", "GPL-1.0-only", "GPL-2.0-only", "GPL-3.0-only",
    "SSPL-1.0", "OSL-3.0", "EUPL-1.1", "EUPL-1.2", "CPAL-1.0", "RPL-1.5",
)
WEAK_COPYLEFT = (
    "LGPL-2.0-only", "LGPL-2.1-only", "LGPL-3.0-only", "MPL-1.1", "MPL-2.0",
    "EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1", "CPL-1.0", "CECILL-C",
)
PERMISSIVE = (
    "0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "BSD-4-Clause", "BSL-1.0",
    "CC0-1.0", "ISC", "MIT", "MIT-0", "MulanPSL-2.0", "PostgreSQL", "PSF-2.0",
    "Python-2.0", "Ruby", "Unlicense", "UPL-1.0", "WTFPL", "Zlib", "ZPL-2.1",
)
PROPRIETARY_MARKERS = ("licenseref-proprietary", "proprietary", "commercial", "unlicensed", "all rights reserved")

DEFAULT_LICENSE_POLICY: dict[str, Any] = {
    "forbidden": [],            # SPDX ids that fail the build
    "restricted": [],           # SPDX ids that require review
    "require_declared": False,  # any component with no declared license is a finding
    "review_copyleft": True,    # copyleft + undeclared/proprietary combination is a finding
    "allowed": [],              # explicitly approved identifiers (a legal decision)
}

_OPERATORS = re.compile(r"\s+(AND|OR|WITH)\s+", re.IGNORECASE)


def _base_id(value: str) -> str:
    """Display form: ``GPL-3.0+`` -> ``GPL-3.0-or-later``. Left as declared otherwise."""
    token = value.strip()
    return re.sub(r"\+$", "-or-later", token)


def license_family(identifier: str) -> str:
    """Comparison key that folds license *variants* of the same family together.

    SPDX writes the same license family many ways — ``GPL-3.0``,
    ``GPL-3.0-only``, ``GPL-3.0-or-later``, ``GPL-3.0+``. For classification and
    for "is this license on the forbidden list" the family is the right
    granularity, so all four collapse to ``gpl-3.0``. Prefixes are preserved, so
    ``LGPL-2.1`` never collapses into ``GPL-2.1``.
    """
    token = _base_id(str(identifier or "")).strip().lower()
    if not token:
        return ""
    # SPDX spells the variant with a hyphen ("GPL-3.0-only"), free-text with a
    # space ("GPL 3.0 or later") — handle both
    token = re.sub(r"[\s-]+(only|or-later)$", "", token)
    token = re.sub(r"[\s-]+or[\s-]+later$", "", token)
    token = token.rstrip("+-. ")
    return token


def normalize_expression(expression: str | None) -> list[dict[str, str]]:
    """SPDX ids in a license expression, with any ``WITH`` exception recorded.

    Returns ``[]`` for empty/ambiguous input — never a guessed identifier.
    """
    raw = str(expression or "").strip()
    if not raw or raw.upper() in ("NOASSERTION", "NONE", "UNKNOWN", "UNLICENSED"):
        return []
    raw = raw.replace("(", " ").replace(")", " ")
    tokens = _OPERATORS.split(raw)
    parts: list[tuple[str, str]] = []      # (license id, exception for that id)
    current = ""
    expecting_exception = False
    for token in tokens:
        upper = token.upper()
        if upper in ("AND", "OR"):
            if current:
                parts.append((current.strip(), ""))
                current = ""
            continue
        if upper == "WITH":
            # the next token is an exception clause belonging to the id before it
            if current:
                parts.append((current.strip(), "\x00pending"))
                current = ""
            expecting_exception = True
            continue
        if expecting_exception:
            identifier, _ = parts[-1]
            parts[-1] = (identifier, token.strip())
            expecting_exception = False
            continue
        current = token.strip()
    if current:
        parts.append((current.strip(), ""))
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for identifier, exception in parts:
        if not identifier or identifier.upper() in ("NOASSERTION", "NONE"):
            continue
        key = identifier.lower()
        if key in seen:
            continue
        seen.add(key)
        entry = {"id": identifier, "base": _base_id(identifier)}
        if exception and exception != "\x00pending":
            entry["exception"] = exception
        out.append(entry)
    return out


def classify(identifier: str) -> str:
    """``strong_copyleft`` | ``weak_copyleft`` | ``permissive`` | ``proprietary`` | ``unknown``."""
    value = str(identifier or "").lower()
    if not value:
        return "unknown"
    if any(marker in value for marker in PROPRIETARY_MARKERS):
        return "proprietary"
    family = license_family(identifier)
    if not family:
        return "unknown"
    for group, label in ((STRONG_COPYLEFT, "strong_copyleft"),
                         (WEAK_COPYLEFT, "weak_copyleft"),
                         (PERMISSIVE, "permissive")):
        if any(license_family(candidate) == family for candidate in group):
            return label
    return "unknown"


def _cdx_components(bom: dict[str, Any]) -> list[dict[str, Any]]:
    return [c for c in (bom.get("components") or []) if isinstance(c, dict)]


def _component_licenses(bom: dict[str, Any]) -> list[tuple[dict[str, Any], list[dict[str, str]]]]:
    """(component, license entries) pairs for either format."""
    from devsecops.sbom_assurance import spdx_components

    out = []
    if str(bom.get("bomFormat") or "").lower() == "cyclonedx":
        for comp in _cdx_components(bom):
            expressions: list[str] = []
            for lic in comp.get("licenses") or []:
                if not isinstance(lic, dict):
                    continue
                if lic.get("expression"):
                    expressions.append(str(lic["expression"]))
                    continue
                detail = lic.get("license") or {}
                if isinstance(detail, dict) and (detail.get("id") or detail.get("name")):
                    expressions.append(str(detail.get("id") or detail.get("name")))
            entries: list[dict[str, str]] = []
            for expression in expressions:
                entries.extend(normalize_expression(expression))
            if not entries and expressions:
                # an expression we could not decompose is still evidence that
                # *something* was declared — record it verbatim rather than
                # dropping it into "undeclared"
                entries = [{"id": expressions[0], "base": expressions[0]}]
            out.append((comp, entries))
        return out
    for pkg in spdx_components(bom):
        declared = str(pkg.get("licenseDeclared") or "")
        entries = normalize_expression(declared)
        if not entries and declared and declared.upper() != "NOASSERTION":
            entries = [{"id": declared, "base": declared}]
        if not entries:
            concluded = normalize_expression(str(pkg.get("licenseConcluded") or ""))
            entries = concluded
        out.append((pkg, entries))
    return out


def _component_name(comp: dict[str, Any]) -> str:
    return str(comp.get("name") or comp.get("SPDXID") or "?")


def _component_version(comp: dict[str, Any]) -> str | None:
    value = comp.get("version") or comp.get("versionInfo")
    return str(value) if value and str(value) != "NOASSERTION" else None


def license_inventory(bom: dict[str, Any] | None, *, max_components_per_license: int = 25) -> dict[str, Any]:
    """Declared licenses grouped by identifier, plus the undeclared components."""
    bom = bom or {}
    pairs = _component_licenses(bom)
    grouped: dict[str, dict[str, Any]] = {}
    undeclared: list[dict[str, str]] = []
    for comp, entries in pairs:
        if not entries:
            undeclared.append({"component": _component_name(comp), "version": _component_version(comp) or ""})
            continue
        for entry in entries:
            key = entry["base"]
            row = grouped.setdefault(key, {
                "spdx_id": entry["id"], "base": entry["base"], "class": classify(entry["base"]),
                "count": 0, "components": [], "exceptions": [],
            })
            row["count"] += 1
            if len(row["components"]) < max_components_per_license:
                row["components"].append({
                    "component": _component_name(comp), "version": _component_version(comp) or ""})
            if entry.get("exception") and entry["exception"] not in row["exceptions"]:
                row["exceptions"].append(entry["exception"])
    licenses = sorted(grouped.values(), key=lambda r: (-r["count"], r["spdx_id"].lower()))
    return {
        "format": "cyclonedx" if str(bom.get("bomFormat") or "").lower() == "cyclonedx" else "spdx",
        "component_count": len(pairs),
        "declared_components": len(pairs) - len(undeclared),
        "licenses": licenses,
        "distinct_licenses": len(licenses),
        "undeclared": undeclared,
        "classes": _class_counts(licenses),
    }


def _class_counts(licenses: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in licenses:
        counts[row["class"]] = counts.get(row["class"], 0) + row["count"]
    return counts


def check_license_policy(bom: dict[str, Any] | None, *,
                         policy: dict[str, Any] | None = None) -> dict[str, Any]:
    """Evaluate a document against a license policy.

    ``verdict`` is ``FAIL`` (forbidden license present), ``REVIEW`` (restricted,
    undeclared, or a copyleft combination that needs a human) or ``PASS``.
    """
    effective = dict(DEFAULT_LICENSE_POLICY)
    effective.update({k: v for k, v in (policy or {}).items() if k in DEFAULT_LICENSE_POLICY})
    inventory = license_inventory(bom)
    # family-aware on purpose: a policy that forbids GPL-3.0 must also catch a
    # component declaring GPL-3.0-or-later, never the other way round
    forbidden = {license_family(x) for x in (effective["forbidden"] or [])}
    restricted = {license_family(x) for x in (effective["restricted"] or [])}

    violations: list[dict[str, Any]] = []
    for row in inventory["licenses"]:
        identifiers = {license_family(row["base"]), license_family(row["spdx_id"])}
        sample = ", ".join(c["component"] for c in row["components"][:5])
        if identifiers & forbidden:
            violations.append({"code": "LICENSE-FORBIDDEN", "severity": "CRITICAL",
                               "spdx_id": row["spdx_id"], "count": row["count"],
                               "detail": f"{row['spdx_id']} is forbidden by policy "
                                         f"({row['count']} component(s): {sample})"})
        elif identifiers & restricted:
            violations.append({"code": "LICENSE-RESTRICTED", "severity": "HIGH",
                               "spdx_id": row["spdx_id"], "count": row["count"],
                               "detail": f"{row['spdx_id']} requires review "
                                         f"({row['count']} component(s): {sample})"})
    if effective["require_declared"] and inventory["undeclared"]:
        names = ", ".join(u["component"] for u in inventory["undeclared"][:5])
        violations.append({"code": "LICENSE-UNDECLARED", "severity": "MEDIUM",
                           "spdx_id": None, "count": len(inventory["undeclared"]),
                           "detail": f"{len(inventory['undeclared'])} component(s) declare no "
                                     f"license: {names}"})

    conflicts = _copyleft_review(inventory) if effective["review_copyleft"] else []
    for conflict in conflicts:
        violations.append({"code": "LICENSE-REVIEW-COPYLEFT", "severity": "MEDIUM",
                           "spdx_id": conflict["spdx_id"], "count": conflict["count"],
                           "detail": conflict["detail"]})

    if any(v["code"] == "LICENSE-FORBIDDEN" for v in violations):
        verdict = "FAIL"
    elif violations:
        verdict = "REVIEW"
    else:
        verdict = "PASS"
    return {"verdict": verdict, "policy": effective, "violations": violations,
            "conflicts": conflicts, "inventory": inventory}


#: The review's vocabulary (item 12). Detected is not approved, and neither is
#: "the policy did not mention it".
LICENSE_STATES: tuple[str, ...] = ("DECLARED", "DETECTED", "UNKNOWN", "CONFLICT",
                                   "POLICY_ACCEPTED", "POLICY_REJECTED", "REQUIRES_REVIEW")


def license_states(bom: dict[str, Any] | None, *, policy: dict[str, Any] | None = None,
                   detected: dict[str, str] | None = None) -> dict[str, Any]:
    """Every component's licence state, in the review's seven-value vocabulary.

    The distinction the review insists on: *license detected* is not *legal
    approval*. So a component's state is one of

    ``DECLARED``        the document states a licence and nothing has reviewed it
    ``DETECTED``        a detector found one and the document declares nothing
    ``CONFLICT``        declaration and detection disagree
    ``POLICY_ACCEPTED`` / ``POLICY_REJECTED``  a policy decision names this family
    ``REQUIRES_REVIEW`` neither a decision nor a detection exists
    ``UNKNOWN``         nothing at all is known about it

    ``detected`` maps a component name to what a file-level detector found; the
    platform never claims detection it did not perform.
    """
    from devsecops.sbom_evidence import license_assessment  # noqa: PLC0415

    effective = dict(DEFAULT_LICENSE_POLICY)
    effective.update({k: v for k, v in (policy or {}).items() if k in DEFAULT_LICENSE_POLICY})
    decisions: dict[str, str] = {}
    for identifier in effective.get("forbidden") or ():
        decisions[license_family(identifier)] = "DENY"
    for identifier in effective.get("restricted") or ():
        decisions.setdefault(license_family(identifier), "REVIEW")
    for identifier in effective.get("allowed") or ():
        decisions.setdefault(license_family(identifier), "ALLOW")

    detector = {str(name).lower(): str(value) for name, value in (detected or {}).items()}
    rows: list[dict[str, Any]] = []
    for component, entries in _component_licenses(bom or {}):
        name = _component_name(component)
        declared = entries[0]["id"] if entries else None
        found = detector.get(name.lower())
        decision = decisions.get(license_family(declared), "") if declared else ""
        policy_map: dict[str, str] = {}
        if decision:
            # both spellings, because a component may declare GPL-3.0-only while
            # the policy names the family GPL-3.0
            policy_map[str(declared).upper()] = decision
            policy_map[str(license_family(declared)).upper()] = decision
        assessment = license_assessment(declared=declared, detected=found,
                                        policy=policy_map or None)
        state = {
            "POLICY_ACCEPTED": "POLICY_ACCEPTED",
            "POLICY_REJECTED": "POLICY_REJECTED",
            "CONFLICT": "CONFLICT",
            "UNKNOWN": "UNKNOWN",
            "REQUIRES_REVIEW": ("REQUIRES_REVIEW" if declared or found else "UNKNOWN"),
        }[assessment["state"]]
        if state in {"REQUIRES_REVIEW", "UNKNOWN"} and found and not declared:
            state = "DETECTED"
        elif state in {"REQUIRES_REVIEW", "UNKNOWN"} and declared and not decision:
            state = "DECLARED"
        rows.append({
            "component": name,
            "version": _component_version(component),
            "declared": declared,
            "detected": found,
            "family": license_family(declared) if declared else None,
            "state": state,
            "approved": state == "POLICY_ACCEPTED",
            "reason": assessment["statement"],
        })
    counts = {state: sum(1 for row in rows if row["state"] == state) for state in LICENSE_STATES}
    approved = counts["POLICY_ACCEPTED"]
    return {
        "counts": counts,
        "components": rows,
        "approved": approved,
        "statement": (
            f"{len(rows)} component(s): {approved} approved by policy, "
            f"{counts['POLICY_REJECTED']} rejected, {counts['REQUIRES_REVIEW']} awaiting "
            f"review, {counts['DECLARED']} declared but unreviewed, "
            f"{counts['UNKNOWN']} unknown"
            + ("" if approved == len(rows) else
               " — a declaration is not an approval, and this list is not legal advice")),
    }


def _copyleft_review(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    """Strong copyleft combined with undeclared/proprietary components.

    Worded as a review trigger on purpose — this is not a compatibility ruling.
    """
    conflicts: list[dict[str, Any]] = []
    copyleft = [row for row in inventory["licenses"] if row["class"] == "strong_copyleft"]
    if not copyleft:
        return conflicts
    risky = [u for u in inventory["undeclared"]]
    proprietary = [row for row in inventory["licenses"] if row["class"] == "proprietary"]
    for row in copyleft:
        reasons = []
        if risky:
            reasons.append(f"{len(risky)} component(s) declare no license")
        if proprietary:
            reasons.append("proprietary license(s) present: "
                           + ", ".join(p["spdx_id"] for p in proprietary[:3]))
        if not reasons:
            continue
        conflicts.append({
            "spdx_id": row["spdx_id"], "count": row["count"],
            "components": [c["component"] for c in row["components"][:5]],
            "detail": f"{row['spdx_id']} (strong copyleft) is combined with "
                      + "; ".join(reasons)
                      + " — flag for legal review; this is a policy trigger, not a compatibility ruling",
        })
    return conflicts


def render_license_report(report: dict[str, Any]) -> str:
    """Markdown for the license section of an SBOM report."""
    inventory = report["inventory"]
    lines = [
        f"License verdict: **{report['verdict']}**",
        "",
        f"- Components: {inventory['component_count']} "
        f"({inventory['declared_components']} declare a license, {len(inventory['undeclared'])} do not)",
        f"- Distinct licenses: {inventory['distinct_licenses']}",
    ]
    if inventory["classes"]:
        lines.append("- By class: " + ", ".join(f"{k} {v}" for k, v in sorted(inventory["classes"].items())))
    if inventory["licenses"]:
        lines += ["", "| License | Class | Components |", "| --- | --- | --- |"]
        for row in inventory["licenses"]:
            exceptions = f" (WITH {', '.join(row['exceptions'])})" if row["exceptions"] else ""
            lines.append(f"| {row['spdx_id']}{exceptions} | {row['class']} | {row['count']} |")
    if inventory["undeclared"]:
        names = ", ".join(u["component"] for u in inventory["undeclared"][:10])
        lines += ["", f"Undeclared licenses ({len(inventory['undeclared'])}): {names}"]
    if report["violations"]:
        lines += ["", "| Code | Severity | Detail |", "| --- | --- | --- |"]
        for violation in report["violations"]:
            lines.append(f"| {violation['code']} | {violation['severity']} | {violation['detail']} |")
    return "\n".join(lines)
