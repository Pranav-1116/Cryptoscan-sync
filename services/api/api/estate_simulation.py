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
    "REMOVE_COMPONENT": {
        "name": "Remove a component",
        "question": "What is left behind if {from} is decommissioned rather than replaced?",
        "inputs": ["from"],
        "optional": ["targets"],
        "answers": [
            "every record that names that component or version",
            "the SBOM/CBOM rows that disappear, and the assets that keep no component fact",
        ],
        "does_not_answer": [
            "what runs in its place — nothing is put in its place here, by design",
            "whether the workload still starts: that is runtime behaviour, not evidence",
        ],
    },
    "CHANGE_KEY_SIZE": {
        "name": "Change a key size",
        "question": "If {from} moved to a {key_size}-bit key, what changes?",
        "inputs": ["from", "key_size"],
        "optional": ["targets"],
        "answers": [
            "which artefacts carry that algorithm or protocol, and what their key size becomes",
            "the CBOM delta for the resized artefacts",
        ],
        "does_not_answer": [
            "whether the library, HSM or peer accepts the larger size — that is a capability claim "
            "nobody made",
            "performance: a larger key has a cost the twin does not measure",
        ],
    },
    "MIGRATE_QUANTUM_VULNERABLE": {
        "name": "Replace everything Shor-vulnerable",
        "question": "If every quantum-vulnerable algorithm became {to}, what does that touch?",
        "inputs": ["to"],
        "optional": ["key_size", "targets"],
        "answers": [
            "every artefact the algorithm registry classifies as Shor-vulnerable, all at once",
            "the CBOM/TLS delta and the assets those artefacts sit on",
        ],
        "does_not_answer": [
            "whether the estate can actually run the target — capability is a blocker, not a promise",
            "anything about confidentiality of traffic already recorded; harvesting is not observable here",
            "agility: replacing the algorithm in the evidence is not replacing it in a deployment",
        ],
    },
    "CUSTOM": {
        "name": "Custom expression",
        "question": "Which records match this condition, and what changes if these facts are set?",
        "inputs": ["expression"],
        "optional": ["targets"],
        "answers": [
            "every evidence record whose facts satisfy the condition tree",
            "the exact before/after of each changed fact, and the six BOMs re-projected from the copy",
            "the blast radius from the changed assets, with the blockers inside it",
        ],
        "does_not_answer": [
            "anything the seven built-in kinds answer more precisely — the custom kind does not "
            "know what an algorithm is, only what a fact says",
            "arithmetic, aggregation or joins across records: the expression reads one record's "
            "facts and writes values, nothing more",
            "a provenance edit: evidence id, source, collector, evidence type and timestamps are "
            "refused, because a simulation may change what the estate says, never who said it",
        ],
    },
    "COMPOSITE": {
        "name": "A sequence of changes",
        "question": "If these changes were applied in order, what does the estate look like after the last one?",
        "inputs": ["steps"],
        "optional": ["targets"],
        "step_fields": ["as_of"],
        "answers": [
            "each step applied to the same copy, in the order given, with the evidence each step matched",
            "the BOM diff of the whole sequence rather than one diff per step to reconcile by hand",
            "the blast radius anchored on the first step's selector and the last step's target",
            "a step may name a stored snapshot with 'as_of': it is then matched against the evidence "
            "that snapshot recorded, while the edit still lands on the estate as it stands — a plan "
            "written in Q2 is judged on Q2's evidence, and a record that has since left the estate is "
            "counted as not_in_current_estate rather than resurrected into the copy",
        ],
        "does_not_answer": [
            "branching, loops or a clock: the sequence is a fixed list of at most 5 primitive "
            "scenarios, applied once, in order. 'as_of' names a *stored snapshot*, never a date — a "
            "date is not evidence",
            "intermediate BOM diffs — only the state after the last step is projected, because a "
            "half-migrated estate is not a deployment anyone asked about",
            "a cascade inside a sequence: a failure propagating through a copy has no BOM diff to "
            "add up, so cascades are refused as steps",
        ],
    },
    "CASCADE_ASSET_UNAVAILABLE": {
        "mode": "CASCADE",
        "name": "Asset goes down",
        "question": "If {seeds} stopped serving, what breaks, wave by wave?",
        "inputs": ["targets"],
        "optional": ["depth"],
        "answers": [
            "each wave of reached assets and the edge that carried the failure to it",
            "the business systems reached, with the route each one was reached by",
            "the refused edges in the radius, which are exactly the places the answer is incomplete",
        ],
        "does_not_answer": [
            "that service stops: redundancy, failover and load balancing are evidence the twin "
            "does not hold",
            "time: a wave is graph distance, not seconds and not an order of failure",
            "the BOMs — a cascade changes no evidence fact, so there is no diff to read",
        ],
    },
    "CASCADE_CRYPTO_COMPROMISE": {
        "mode": "CASCADE",
        "name": "Crypto on an asset is compromised",
        "question": "If the cryptography on {seeds} is treated as broken, whose assurance follows?",
        "inputs": ["targets"],
        "optional": ["depth"],
        "answers": [
            "everything whose assurance rests on those keys, certificates, algorithms or libraries",
            "the systems reached, and the edge each one inherits the compromise through",
        ],
        "does_not_answer": [
            "that a compromise happened — this models inherited assurance, not an incident",
            "what data was exposed: the twin records that crypto is used, not what it protected",
            "repair: rotation and re-issuance are a remediation plan, not a traversal",
        ],
    },
    "CASCADE_TRUST_COMPROMISE": {
        "mode": "CASCADE",
        "name": "A CA or PKI issuer is compromised",
        "question": "If the trust anchor or issuing CA behind {seeds} is no longer trustworthy, what stops being vouched for?",
        "inputs": ["targets"],
        "optional": ["depth"],
        "answers": [
            "everything that issuer or signer vouches for, walked over issued_by, signed_by, "
            "verified_by, uses_certificate and terminates_tls_for",
            "the systems reached, and the edge each one inherits the broken trust through",
            "the trust-store and revocation blind spots, listed rather than assumed away",
        ],
        "does_not_answer": [
            "that a compromise happened — this models inherited assurance, not an incident",
            "trust-store membership: a host that trusts a root the twin never collected is invisible, "
            "so where the walk stops is a collection gap, not the boundary of trust",
            "revocation: CRL/OCSP publication and vendor soft-fail behaviour are not in the model, so "
            "'reached' never means 'rejected by every verifier'",
            "cross-signing and name constraints: the radius is a superset of a correct PKI walk",
        ],
    },
    "CASCADE_ALGORITHM_BREAK": {
        "mode": "CASCADE",
        "name": "An algorithm breaks everywhere",
        "question": "If {from} became untrustworthy tonight, what is reached from every use of it?",
        "inputs": ["from"],
        "optional": ["depth", "targets"],
        "answers": [
            "every asset using it, as the seeds of one event rather than forty incidents",
            "the waves outward through keys, certificates, libraries, endpoints and the systems "
            "that contain them",
        ],
        "does_not_answer": [
            "harvest-now-decrypt-later: traffic recorded before the break is not observable here",
            "fallback: a peer may negotiate something else, which is a configuration claim nobody made",
            "the BOMs — a cascade changes no evidence fact",
        ],
    },
}

#: The two families the workspace offers. A scenario edits a fact on a copy; a cascade
#: propagates a failure through the topology and edits nothing. They share the preview and
#: the quarantine because both are questions asked of the estate.
MODES: dict[str, dict[str, Any]] = {
    "SCENARIO": {
        "name": "Change the estate",
        "blurb": (
            "apply a change to a copy of the twin, re-project the six BOMs from that copy, and "
            "report the diff, the blast radius and the blockers"
        ),
        "changes_evidence": True,
        "has_bom_diff": True,
    },
    "CASCADE": {
        "name": "Cascade a failure",
        "blurb": (
            "propagate a failure through the established dependency edges and report what is "
            "reached, wave by wave — no evidence changes, so there is no BOM diff"
        ),
        "changes_evidence": False,
        "has_bom_diff": False,
    },
}

for _kind, _detail in KIND_CATALOG.items():
    _detail.setdefault("mode", "SCENARIO")

LIMITS = [
    "a simulation is a question asked of a copy: it is quarantined, never counted as estate state, "
    "and never changes the live projection id",
    "the answer is only as complete as the evidence behind it — an uncollected source is invisible, "
    "and the result says so rather than reporting zero impact",
    "scenarios change evidence facts; they do not model configuration, traffic, approvals or a "
    "deployment plan",
    "a stored run is measured against the evidence state it was computed from and is marked "
    "superseded once the estate moves",
    "a cascade propagates a failure over *established* edges only: a refused relationship is not "
    "in the topology, so its blind spots are listed rather than assumed away — and a wave is graph "
    "distance, not time",
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


#: Edges along which "what rests on this" is answerable. Used only to decide which assets
#: are worth offering as a cascade seed — the walking itself is the engine's job.
_RESTED_ON_PREDICATES = frozenset(
    {
        "runs_on",
        "hosted_on",
        "depends_on",
        "connects_to",
        "routes_to",
        "protected_by",
        "uses_hsm",
        "uses_kms",
        "signed_by",
        "issued_by",
    }
)


def presets(graph: Any, vocabulary: Mapping[str, Any] | None = None, *, limit: int = 12) -> list[dict[str, Any]]:
    """Questions this estate can already be asked, built from its own vocabulary.

    A workspace with an empty form asks the operator to invent a scenario, and the most
    common invented scenario is one nothing matches. These are seeded from the values and
    the topology the twin actually holds, so the first run is usually a real one. Each
    preset is a *starting point*, not a finding: it carries the mode and the scenario, and
    the console still previews before it runs.
    """
    vocabulary = vocabulary or selector_vocabulary(graph)
    out: list[dict[str, Any]] = []

    for item in list(vocabulary.get("algorithms") or [])[:3]:
        value = item["value"]
        out.append(
            {
                "id": f"retire:{value}",
                "label": f"Retire {value}",
                "mode": "SCENARIO",
                "kind": "RETIRE_ALGORITHM",
                "scenario": {"kind": "RETIRE_ALGORITHM", "from": value},
                "why": f"{item['count']} artefact(s) in this estate use it",
            }
        )
        out.append(
            {
                "id": f"break:{value}",
                "label": f"If {value} broke tonight",
                "mode": "CASCADE",
                "kind": "CASCADE_ALGORITHM_BREAK",
                "scenario": {"kind": "CASCADE_ALGORITHM_BREAK", "from": value},
                "why": f"{item['count']} artefact(s) would be seeds at once",
            }
        )

    for item in list(vocabulary.get("protocols") or [])[:2]:
        out.append(
            {
                "id": f"disable:{item['value']}",
                "label": f"Disable {item['value']}",
                "mode": "SCENARIO",
                "kind": "DISABLE_PROTOCOL",
                "scenario": {"kind": "DISABLE_PROTOCOL", "from": item["value"]},
                "why": f"negotiated on {item['count']} artefact(s)",
            }
        )

    for item in list(vocabulary.get("components") or [])[:2]:
        out.append(
            {
                "id": f"upgrade:{item['value']}",
                "label": f"Upgrade {item['value']}",
                "mode": "SCENARIO",
                "kind": "UPGRADE_COMPONENT",
                "scenario": {"kind": "UPGRADE_COMPONENT", "from": item["value"]},
                "why": f"named on {item['count']} record(s) — add a target version to run it",
            }
        )

    dependents: dict[str, int] = {}
    try:
        relationships = graph.relationships()
    except Exception:  # noqa: BLE001 — a preset list is a convenience, never a gate
        relationships = []
    for edge in relationships:
        predicate = str(edge.get("predicate") or "")
        if predicate in _RESTED_ON_PREDICATES:
            target = str(edge.get("object") or "")
            if target:
                dependents[target] = dependents.get(target, 0) + 1

    for asset_id, count in sorted(dependents.items(), key=lambda item: (-item[1], item[0]))[:3]:
        asset = (graph.asset(asset_id) if hasattr(graph, "asset") else None) or {}
        name = asset.get("name") or asset_id
        out.append(
            {
                "id": f"down:{asset_id}",
                "label": f"If {name} goes down",
                "mode": "CASCADE",
                "kind": "CASCADE_ASSET_UNAVAILABLE",
                "scenario": {"kind": "CASCADE_ASSET_UNAVAILABLE", "targets": [asset_id]},
                "why": f"{count} established edge(s) rest on it",
            }
        )

    return out[:limit]


def catalog(graph: Any) -> dict[str, Any]:
    """Everything the workspace needs to render a form and its limits in one response."""
    summary = graph.summary()
    coverage = graph.coverage()["summary"]
    vocabulary = selector_vocabulary(graph)
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
        "modes": [{"mode": mode, **detail} for mode, detail in MODES.items()],
        "kinds": [
            {"kind": kind, **detail} for kind, detail in KIND_CATALOG.items()
        ],
        "presets": presets(graph, vocabulary),
        "selector": vocabulary,
        "note": (
            "a scenario is applied to a copy of this twin; the live projection id above is captured "
            "before and after the run and must be identical. A cascade is not applied to a copy — it "
            "walks the live topology and changes nothing, which is why it has no BOM diff"
        ),
        "limits": LIMITS,
    }


def mode_of(kind: str) -> str:
    """Which family a kind belongs to. Unknown kinds are treated as scenarios so the
    engine, not this module, produces the refusal."""
    return str(KIND_CATALOG.get(str(kind or "").upper(), {}).get("mode") or "SCENARIO")


def plan(
    graph: Any,
    scenario: Mapping[str, Any],
    *,
    as_of_graphs: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Would this selector match anything? Answered before the run, from the live twin.

    ``as_of_graphs`` is passed through untouched: a ``COMPOSITE`` step that names a
    stored snapshot is previewed against that snapshot, and the caller — which is the
    only layer that can read the snapshot table — decides which ids resolve.
    """
    result = estate_twin.preview(graph, scenario, as_of_graphs=as_of_graphs)
    return {**result, "workspace": SCHEMA, "mode": mode_of(str(scenario.get("kind") or ""))}


def run(
    graph: Any,
    scenario: Mapping[str, Any],
    *,
    as_of_graphs: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Apply the scenario to a copy and return the answer the engine produced.

    Deliberately a thin call: the engine owns the copy, the re-projection and the
    before/after projection check, and this module must not grow a second opinion.
    """
    result = estate_twin.simulate(graph, scenario, as_of_graphs=as_of_graphs)
    return {**result, "workspace": SCHEMA, "mode": mode_of(str(scenario.get("kind") or ""))}
