"""What a licence asks of *this* distribution, not of licences in general.

Guide 135 produced the seven states — declared, detected, conflict, accepted,
rejected, review, unknown. Those say what is *known* about a component's
licence. They cannot say what it obliges, because an obligation depends on how
the software leaves the building:

* an internal service that never ships a binary has no distribution trigger;
* a binary shipped to customers triggers attribution and, for copyleft, source
  disclosure for the covered parts;
* anything reachable over the network triggers the network clause of the AGPL;
* modified LGPL code carries a relinking obligation that an unmodified
  dependency does not.

So this module is a **rule table plus an engine**, and its output is a checklist
with a status per duty — ``TRIGGERED``, ``NOT_TRIGGERED``, ``UNKNOWN``. It never
returns "compliant": which obligations a bank accepts is a decision for its
counsel, and a tool that answers it would be giving legal advice.

The rules cite the clause they come from so a reviewer can check them, and
every unknown is visible: an unknown licence family yields ``UNKNOWN`` duties
rather than an empty checklist that reads like a clean one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

SCHEMA = "cryptoscan.license-obligations/1"

#: How the software reaches the outside world. This is the axis the states in
#: guide 135 do not have, and the one obligations depend on.
DISTRIBUTION_MODELS: tuple[str, ...] = ("INTERNAL", "SAAS", "BINARY_SHIPPED",
                                        "SOURCE_DISTRIBUTED")

MODEL_LABELS: dict[str, str] = {
    "INTERNAL": "used inside the bank; no binary or source leaves the estate",
    "SAAS": "reachable by third parties over a network, operated by the bank",
    "BINARY_SHIPPED": "compiled artifact delivered to a customer or partner",
    "SOURCE_DISTRIBUTED": "source delivered to a customer or published",
}

#: Licence families, coarse on purpose: the engine decides duties, not the
#: wording of an identifier.
FAMILIES: tuple[str, ...] = ("PERMISSIVE", "WEAK_COPYLEFT", "STRONG_COPYLEFT",
                             "NETWORK_COPYLEFT", "PUBLIC_DOMAIN", "NON_COMMERCIAL",
                             "PROPRIETARY", "UNKNOWN")


@dataclass(frozen=True)
class Obligation:
    """One duty a licence may impose, and the clause it comes from."""

    id: str
    title: str
    basis: str
    cite: str
    severity: str = "MEDIUM"


OBLIGATIONS: dict[str, Obligation] = {
    obligation.id: obligation for obligation in (
        Obligation("NOTICE_FILE", "Ship the licence text and copyright notices",
                   "distribution of the work requires the licence and notices to travel "
                   "with it", "Apache-2.0 §4(a); MIT 'included in all copies'", "MEDIUM"),
        Obligation("ATTRIBUTION", "Credit the authors in documentation or an about screen",
                   "attribution is required wherever the work is redistributed",
                   "BSD-3-Clause clause 2; Apache-2.0 §4(b)", "LOW"),
        Obligation("SOURCE_DISCLOSURE",
                   "Offer the corresponding source of the covered component",
                   "conveying a binary of copyleft code requires the corresponding source "
                   "for that code", "GPL-2.0 §3; GPL-3.0 §6", "HIGH"),
        Obligation("DERIVATIVE_SCOPE",
                   "Establish whether the bank's own code is a derivative work",
                   "copyleft reaches derivative works, and linking/aggregation decides that",
                   "GPL-3.0 §5; GPL-2.0 §2", "HIGH"),
        Obligation("NETWORK_SOURCE_OFFER",
                   "Offer the source to users interacting with it over a network",
                   "the network clause extends copyleft to remote interaction",
                   "AGPL-3.0 §13", "HIGH"),
        Obligation("RELINKING", "Allow relinking against a modified LGPL component",
                   "replacing a modified LGPL library must remain possible for the user",
                   "LGPL-3.0 §4(d); LGPL-2.1 §6", "MEDIUM"),
        Obligation("MODIFICATION_DISCLOSURE",
                   "Publish changes made to a copyleft component",
                   "modified copyleft files must carry prominent change notices",
                   "GPL-3.0 §5(a); LGPL-3.0 §4(a)", "MEDIUM"),
        Obligation("PATENT_GRANT", "Do not initiate patent litigation over the work",
                   "the patent grant terminates on an infringement action",
                   "Apache-2.0 §3; GPL-3.0 §11", "LOW"),
        Obligation("NOTICE_PRESERVATION", "Preserve the NOTICE file contents",
                   "attribution notices in NOTICE must be retained in redistribution",
                   "Apache-2.0 §4(d)", "LOW"),
        Obligation("COMMERCIAL_TERMS", "Confirm the commercial terms for this component",
                   "proprietary components are governed by their own agreement, not by an "
                   "OSI licence", "the vendor agreement", "HIGH"),
        Obligation("TERMS_UNKNOWN", "Establish the licence before deciding any duty",
                   "an unidentified licence cannot be reasoned about",
                   "n/a — the licence is unknown", "HIGH"),
        Obligation("NC_USE_RESTRICTION",
                   "Confirm the licence permits this commercial use",
                   "a non-commercial licence forbids use by a commercial entity, whatever "
                   "the distribution model", "CC-BY-NC-4.0 §2(a)(1)", "HIGH"),
        Obligation("NO_OBLIGATION", "No obligations identified for this family",
                   "public-domain dedications impose no attribution or source duty in the "
                   "jurisdictions this table covers", "CC0-1.0 (as a dedication)", "INFO"),
    )
}


_FAMILY_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("NETWORK_COPYLEFT", ("agpl",)),
    ("WEAK_COPYLEFT", ("lgpl", "mpl-2", "epl-", "cddl")),
    ("STRONG_COPYLEFT", ("gpl-", "gplv", "gpl-2", "gpl-3", "sspl", "osl", "eupl")),
    ("PUBLIC_DOMAIN", ("cc0", "unlicense", "public-domain", "wtfpl")),
    ("NON_COMMERCIAL", ("-nc", "noncommercial", "non-commercial", "cc-by-nc")),
    ("PROPRIETARY", ("proprietary", "commercial", "licenseref", "all rights reserved")),
    ("PERMISSIVE", ("mit", "apache", "bsd", "isc", "zlib", "python-2", "psf", "bsl-1")),
)


def family_for_licence(identifier: str | None) -> str:
    """Map an SPDX identifier (or a family name) to this table's coarse family.

    Coarse on purpose: an obligation engine that tried to model every licence
    would be making the legal judgement it is meant to hand to counsel.
    """
    text = str(identifier or "").strip().lower()
    if not text:
        return "UNKNOWN"
    upper = text.upper()
    if upper in FAMILIES:
        return upper
    for family, markers in _FAMILY_MARKERS:
        if any(marker in text for marker in markers):
            return family
    return "UNKNOWN"


def _rule(family: str, model: str) -> list[str]:
    """The obligation ids a family triggers under a distribution model."""
    if family == "PUBLIC_DOMAIN":
        return ["NO_OBLIGATION"]
    if family == "UNKNOWN":
        return ["TERMS_UNKNOWN"]
    if family == "PROPRIETARY":
        # no distribution model makes a commercial licence answerable by this table
        return ["COMMERCIAL_TERMS"]
    if family == "NON_COMMERCIAL":
        # the restriction is on *use*, so every model triggers it — including
        # internal use by a commercial bank
        return ["NC_USE_RESTRICTION"]
    duties: list[str] = []
    if model in {"BINARY_SHIPPED", "SOURCE_DISTRIBUTED"}:
        duties += ["NOTICE_FILE", "ATTRIBUTION"]
    if family == "PERMISSIVE":
        if model == "BINARY_SHIPPED":
            duties += ["NOTICE_PRESERVATION"]
        duties += ["PATENT_GRANT"]
    elif family == "WEAK_COPYLEFT":
        if model in {"BINARY_SHIPPED", "SOURCE_DISTRIBUTED"}:
            duties += ["SOURCE_DISCLOSURE", "RELINKING", "MODIFICATION_DISCLOSURE",
                       "DERIVATIVE_SCOPE"]
        elif model == "SAAS":
            duties += ["DERIVATIVE_SCOPE"]
    elif family == "STRONG_COPYLEFT":
        if model in {"BINARY_SHIPPED", "SOURCE_DISTRIBUTED"}:
            duties += ["SOURCE_DISCLOSURE", "DERIVATIVE_SCOPE", "MODIFICATION_DISCLOSURE"]
        elif model == "SAAS":
            # the GPL is not triggered by use over a network; the AGPL is. Both are
            # narrowed to a review rather than asserted either way.
            duties += ["DERIVATIVE_SCOPE"]
    elif family == "NETWORK_COPYLEFT":
        duties += ["DERIVATIVE_SCOPE", "MODIFICATION_DISCLOSURE"]
        if model == "SAAS":
            duties += ["NETWORK_SOURCE_OFFER"]
        elif model in {"BINARY_SHIPPED", "SOURCE_DISTRIBUTED"}:
            duties += ["SOURCE_DISCLOSURE", "NETWORK_SOURCE_OFFER"]
    return duties


def obligations_for(licence: str, *, family: str, model: str,
                    modified: bool = False) -> dict[str, Any]:
    """The duties this licence imposes on this distribution, and their status.

    ``modified`` matters: a change notice and a relinking duty attach to a
    component the bank has patched, not to the same component as published.
    """
    model = str(model or "").upper()
    family = str(family or "UNKNOWN").upper()
    if model not in DISTRIBUTION_MODELS:
        raise ValueError(f"distribution model must be one of {', '.join(DISTRIBUTION_MODELS)}")
    if family not in FAMILIES:
        family = "UNKNOWN"
    triggered = set(_rule(family, model))
    if (modified and family == "PERMISSIVE"
            and model in {"BINARY_SHIPPED", "SOURCE_DISTRIBUTED"}
            and "apache" in str(licence or "").lower()):
        # Apache-2.0 §4(b) is the permissive licence that demands change notices;
        # MIT and BSD do not, so this cannot be a family-wide rule
        triggered.add("MODIFICATION_DISCLOSURE")
    if not modified:
        triggered.discard("MODIFICATION_DISCLOSURE")
    rows: list[dict[str, Any]] = []
    for duty in {spec.id for spec in OBLIGATIONS.values()}:
        spec = OBLIGATIONS[duty]
        status = "TRIGGERED" if duty in triggered else "NOT_TRIGGERED"
        rows.append({"id": spec.id, "title": spec.title, "state": status,
                     "basis": spec.basis, "cite": spec.cite, "severity": spec.severity})
    rows.sort(key=lambda row: (row["state"] != "TRIGGERED", row["id"]))
    open_duties = [row["id"] for row in rows if row["state"] == "TRIGGERED"]
    return {
        "schema": SCHEMA,
        "licence": licence,
        "family": family,
        "model": model,
        "modified": bool(modified),
        "obligations": rows,
        "open": open_duties,
        "verdict": ("NEEDS_LEGAL" if family in {"UNKNOWN", "PROPRIETARY", "NON_COMMERCIAL"}
                    else "REVIEW" if open_duties else "NO_ACTION"),
        "statement": (
            f"{licence or 'unknown licence'} ({family}) under {model}: "
            + (f"{len(open_duties)} dut{'y' if len(open_duties) == 1 else 'ies'} to check — "
               f"{', '.join(open_duties[:4])}" if open_duties else "no duties identified")
            + " — a checklist for counsel, not a legal opinion"),
    }


def portfolio_obligations(components: Iterable[Mapping[str, Any]], *, model: str,
                          family_of: Any = None) -> dict[str, Any]:
    """The obligations across a bill of materials, grouped by duty.

    ``components`` rows carry at least ``name`` and ``licence``; ``family_of``
    maps a licence id to a family (the caller passes
    ``sbom_license.license_family``-based classification so the two modules
    cannot disagree about what GPL-3.0-only is).
    """
    model = str(model or "").upper()
    if model not in DISTRIBUTION_MODELS:
        raise ValueError(f"distribution model must be one of {', '.join(DISTRIBUTION_MODELS)}")
    grouped: dict[str, dict[str, Any]] = {}
    rows: list[dict[str, Any]] = []
    unknown: list[str] = []
    for component in components:
        licence = str(component.get("licence") or "").strip()
        name = str(component.get("name") or "?")
        family = (str(family_of(licence)) if family_of else family_for_licence(licence))
        family = str(family or "UNKNOWN").upper()
        if family not in FAMILIES:
            family = family_for_licence(family)
        if family == "UNKNOWN":
            unknown.append(name)
        result = obligations_for(licence, family=family, model=model,
                                 modified=bool(component.get("modified")))
        rows.append({"component": name, "licence": licence or None, "family": family,
                     "open": result["open"], "verdict": result["verdict"]})
        for duty in result["open"]:
            entry = grouped.setdefault(duty, {"id": duty,
                                              "title": OBLIGATIONS[duty].title,
                                              "cite": OBLIGATIONS[duty].cite,
                                              "components": []})
            entry["components"].append(name)
    counts = {duty: len(entry["components"]) for duty, entry in grouped.items()}
    return {
        "schema": SCHEMA,
        "model": model,
        "components": rows,
        "duties": sorted(grouped.values(), key=lambda row: row["id"]),
        "counts": dict(sorted(counts.items())),
        "unknown_components": unknown,
        "verdict": "NEEDS_LEGAL" if unknown else ("REVIEW" if grouped else "NO_ACTION"),
        "statement": (
            f"{len(rows)} component(s) under {model}: {len(grouped)} distinct dut"
            f"{'y' if len(grouped) == 1 else 'ies'}, {len(unknown)} component(s) with no "
            "identified licence — a checklist for counsel, not a legal opinion"),
    }
