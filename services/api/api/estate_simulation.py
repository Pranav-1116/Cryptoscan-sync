"""The simulation workspace: ask "what if" against the estate, and never bend the estate.

A simulation is the one place in this product where an answer is *invented* — the
scenario never happened. Everything here exists to keep that honest:

* **the scenario is applied to a copy.** :func:`shared_models.estate_twin.simulate`
  deep-copies the snapshot, rebuilds the graph from it and re-projects the six BOMs.
  The live projection id is captured before and after, so "the estate did not move"
  is checked rather than promised, and this module refuses to store a result that
  reports otherwise;
* **a question is not an observation.** Stored runs are quarantined by
  :mod:`api.estate_simulation_store` and carry the evidence state they were computed
  against, so an old answer about a different estate is marked superseded instead of
  being read as today's impact;
* **"no match" is not "no impact".** The estate may not describe the artefact, or may
  never have collected the source that would. That sentence travels with the result,
  and the *preview* exists so an operator sees it before spending the run;
* **the selector vocabulary is the estate's own.** The catalog lists the algorithms,
  protocols and components the twin actually holds, with counts, because the most
  common way to get a useless answer here is to type an algorithm name the estate
  spells differently — or has never seen.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from shared_models import estate_twin

SCHEMA = "cryptoscan.simulation-workspace/1"

#: What each scenario kind answers, and what it deliberately does not. Repeated in the
#: catalog response so the console cannot render a kind without its limit.
KIND_CATALOG: dict[str, dict[str, Any]] = {
    "REPLACE_ALGORITHM": {
        "name": "Replace an algorithm",
        "question": "If every use of {from} became {to}, what changes and what breaks?",
        "inputs": ["from", "to"],
        "optional": ["key_size", "targets"],
        "answers": [
            "which evidence records would change, and to what",
            "how the six BOMs differ between the live twin and the copy",
            "the blast radius from the changed assets, and the blockers inside it",
        ],
        "does_not_answer": [
            "whether the target algorithm is supported by a library, HSM or peer — a blocker is "
            "reported, an implementation is not proven",
            "whether the change is approved, funded or scheduled",
            "whether the estate you have is the estate you have: an uncollected source is invisible here",
        ],
    },
    "RETIRE_ALGORITHM": {
        "name": "Retire an algorithm",
        "question": "What is left behind if {from} is withdrawn entirely?",
        "inputs": ["from"],
        "optional": ["targets"],
        "answers": [
            "every artefact that would lose its algorithm or protocol",
            "which of those assets stay in the twin with no crypto fact at all",
            "how HBOM/VBOM/CBOM projections change when the artefact goes",
        ],
        "does_not_answer": [
            "whether the dependent system still works — the twin models evidence, not runtime "
            "behaviour",
            "commercial or contractual consequences of withdrawal",
        ],
    },
    "DISABLE_PROTOCOL": {
        "name": "Disable a protocol",
        "question": "What stops negotiating if {from} is switched off?",
        "inputs": ["from"],
        "optional": ["targets"],
        "answers": [
            "every endpoint and library whose protocol would be removed",
            "the NBOM and CBOM delta, and the relationships that lose their basis",
        ],
        "does_not_answer": [
            "whether a peer would fall back to another protocol: a fallback is a configuration "
            "claim the collectors did not make",
            "anything about a live handshake — that needs a runtime observation",
        ],
    },
    "UPGRADE_COMPONENT": {
        "name": "Upgrade a component",
        "question": "What does moving {from} to {to} touch in the estate?",
        "inputs": ["from", "to"],
        "optional": ["targets"],
        "answers": [
            "which records name that component or version, and what they follow to",
            "the SBOM/CBOM delta and the assets that share the component",
        ],
        "does_not_answer": [
            "compatibility: the twin records that a version changed, never that the new version "
            "runs the old workload",
            "the contents of the new version — that is a scan of a different estate",
        ],
    },
}

LIMITS = [
    "a simulation is a question asked of a copy: it is quarantined, never counted as estate state, "
    "and never changes the live projection id",
    "the answer is only as complete as the evidence behind it — an uncollected source is invisible, "
    "and the result says so rather than reporting zero impact",
    "scenarios change evidence facts; they do not model configuration, traffic, approvals or a "
    "deployment plan",
    "a stored run is measured against the evidence state it was computed from and is marked "
    "superseded once the estate moves",
]


def _count(values: Iterable[Any]) -> dict[str, int]:
    out: dict[str, int] = {}
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        out[text] = out.get(text, 0) + 1
    return dict(sorted(out.items(), key=lambda item: (-item[1], item[0])))


def selector_vocabulary(graph: Any, *, limit: int = 40) -> dict[str, Any]:
    """The values this estate actually holds, so a selector can be picked, not guessed.

    Every entry carries a count: a value seen once is a different decision from one seen
    on four hundred records, and a value with no count would look like a suggestion.
    """
    algorithms: list[dict[str, Any]] = []
    protocols: list[dict[str, Any]] = []
    components: list[dict[str, Any]] = []
    try:
        artifacts = graph.crypto_artifacts()
    except Exception:  # noqa: BLE001 — a vocabulary is a convenience, never a gate
        artifacts = []
    alg_counts = _count(item.get("algorithm") for item in artifacts)
    proto_counts = _count(item.get("protocol") for item in artifacts)
    for value, count in list(alg_counts.items())[:limit]:
        algorithms.append({"value": value, "count": count})
    for value, count in list(proto_counts.items())[:limit]:
        protocols.append({"value": value, "count": count})

    comp_counts: dict[str, int] = {}
    for record in graph.evidence():
        facts = record.get("facts") or {}
        value = facts.get("name") or facts.get("component")
        version = facts.get("version")
        if not value:
            continue
        label = f"{value} {version}".strip() if version else str(value)
        comp_counts[label] = comp_counts.get(label, 0) + 1
    for value, count in sorted(comp_counts.items(), key=lambda item: (-item[1], item[0]))[:limit]:
        components.append({"value": value, "count": count})

    targets = [
        {
            "asset_id": asset.get("asset_id"),
            "name": asset.get("name"),
            "type": asset.get("type"),
        }
        for asset in sorted(
            graph.assets(), key=lambda item: str(item.get("name") or item.get("asset_id"))
        )[:limit]
    ]
    return {
        "algorithms": algorithms,
        "protocols": protocols,
        "components": components,
        "targets": targets,
        "truncated_to": limit,
        "note": (
            "these are the values this estate holds. A value that is not here is not forbidden — "
            "it is a value no collector has reported, and a scenario using it will not match"
        ),
    }


def catalog(graph: Any) -> dict[str, Any]:
    """Everything the workspace needs to render a form and its limits in one response."""
    summary = graph.summary()
    coverage = graph.coverage()["summary"]
    return {
        "schema": SCHEMA,
        "base_projection_id": graph.fingerprint(),
        "estate": {
            "assets": summary.get("assets"),
            "evidence": summary.get("evidence"),
            "relationships": summary.get("relationships"),
            "coverage_state": coverage.get("coverage_state"),
            "attempted": coverage.get("attempted"),
            "collected": coverage.get("collected"),
        },
        "kinds": [
            {"kind": kind, **detail} for kind, detail in KIND_CATALOG.items()
        ],
        "selector": selector_vocabulary(graph),
        "note": (
            "a scenario is applied to a copy of this twin; the live projection id above is captured "
            "before and after the run and must be identical"
        ),
        "limits": LIMITS,
    }


def plan(graph: Any, scenario: Mapping[str, Any]) -> dict[str, Any]:
    """Would this selector match anything? Answered before the run, from the live twin."""
    result = estate_twin.preview(graph, scenario)
    return {**result, "workspace": SCHEMA}


def run(graph: Any, scenario: Mapping[str, Any]) -> dict[str, Any]:
    """Apply the scenario to a copy and return the answer the engine produced.

    Deliberately a thin call: the engine owns the copy, the re-projection and the
    before/after projection check, and this module must not grow a second opinion.
    """
    result = estate_twin.simulate(graph, scenario)
    return {**result, "workspace": SCHEMA}
